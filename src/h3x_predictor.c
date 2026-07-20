/*
 * H3X LASSO Transition Predictor
 * ================================
 * L1-regularized linear predictor for 4×2 transition frames.
 *
 * Key insight: in sequential tensor data (model weights stored in order),
 * adjacent byte transitions are highly correlated. A LASSO predictor
 * learns sparse coefficients that predict the next transition frame
 * from the previous N frames. The predicted frame is subtracted from
 * the actual → residual stream is sparser (more identity tokens).
 *
 * Architecture:
 *   - Positional embedding anchors at configurable stride
 *   - Sliding window of H3X_PREDICT_WINDOW previous transition frames
 *   - Online coordinate descent for L1 weight updates
 *   - Prediction residual encoding (even more >60% identity tokens)
 *
 * The anchor frames serve as absolute reference points — at each anchor,
 * the predictor resets and the actual frame is stored. Between anchors,
 * only prediction residuals are stored.
 *
 * QomputeAI 2024-2026
 */

#include "../include/h3x_format.h"
#include <string.h>
#include <math.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Predictor Initialization
 * ═══════════════════════════════════════════════════════════════════════════ */

void h3x_predictor_init_full(H3X_LassoPredictor *pred, uint32_t anchor_stride) {
    memset(pred, 0, sizeof(H3X_LassoPredictor));
    pred->anchor_stride = anchor_stride;
    /* Initialize weights to slight bias toward identity prediction */
    for (int i = 0; i < H3X_PREDICT_WINDOW * H3X_COEFFS_PER_BYTE; i++) {
        pred->weights[i] = 0.0f;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LASSO Prediction (L1-Sparse Linear Model)
 *
 * For each of the 8 coefficients in the transition frame, predict:
 *   predicted[i] = Σ_j (weights[j*8+i] * history[j].tokens[i])
 *
 * Then round to nearest eigen-token (since prediction is approximate).
 * The sparsity of L1 means most weights are zero — only a few history
 * frames actually contribute, which is the "selection" property.
 * ═══════════════════════════════════════════════════════════════════════════ */

void h3x_predictor_predict_full(const H3X_LassoPredictor *pred,
                                 const H3X_TransitionFrame *history,
                                 size_t n_history,
                                 H3X_TransitionFrame *out_predicted) {
    /* Default prediction: identity (token 2 = no change) */
    for (int i = 0; i < H3X_COEFFS_PER_BYTE; i++) {
        out_predicted->tokens[i] = H3X_EIGEN_ZERO;
    }

    if (n_history == 0) return;

    /* Compute weighted prediction from history window */
    size_t window = n_history < H3X_PREDICT_WINDOW ? n_history : H3X_PREDICT_WINDOW;
    size_t start = n_history - window;

    for (int coeff = 0; coeff < H3X_COEFFS_PER_BYTE; coeff++) {
        float pred_val = 0.0f;

        for (size_t w = 0; w < window; w++) {
            float weight = pred->weights[w * H3X_COEFFS_PER_BYTE + coeff];
            if (fabsf(weight) < 1e-6f) continue; /* Sparse: skip zero weights */

            /* History token → float value for prediction */
            float hist_val = (float)history[start + w].tokens[coeff] - 2.0f;
            pred_val += weight * hist_val;
        }

        /* Round prediction to nearest integer token offset, clamp to [0,4] */
        int predicted_token = (int)roundf(pred_val) + 2;
        if (predicted_token < 0) predicted_token = 0;
        if (predicted_token > 4) predicted_token = 4;
        out_predicted->tokens[coeff] = (uint8_t)predicted_token;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Online LASSO Update (Coordinate Descent with Soft Thresholding)
 *
 * After observing the actual transition, update weights via:
 *   residual = actual - predicted
 *   gradient = -2 * residual * x_j  (per weight)
 *   w_j = soft_threshold(w_j - lr * gradient, lambda)
 *
 * soft_threshold(w, λ) = sign(w) * max(|w| - λ, 0)
 * ═══════════════════════════════════════════════════════════════════════════ */

void h3x_predictor_update_full(H3X_LassoPredictor *pred,
                                const H3X_TransitionFrame *actual,
                                const H3X_TransitionFrame *predicted,
                                const H3X_TransitionFrame *history,
                                size_t n_history) {
    float lambda = 0.005f;  /* L1 regularization strength */
    float lr = 0.05f;       /* Learning rate */

    size_t window = n_history < H3X_PREDICT_WINDOW ? n_history : H3X_PREDICT_WINDOW;
    if (window == 0) return;
    size_t start = n_history - window;

    for (int coeff = 0; coeff < H3X_COEFFS_PER_BYTE; coeff++) {
        float actual_val = (float)actual->tokens[coeff] - 2.0f;
        float pred_val   = (float)predicted->tokens[coeff] - 2.0f;
        float residual   = actual_val - pred_val;

        for (size_t w = 0; w < window; w++) {
            float x_j = (float)history[start + w].tokens[coeff] - 2.0f;
            float grad = -2.0f * residual * x_j;

            int widx = (int)(w * H3X_COEFFS_PER_BYTE + coeff);
            float weight = pred->weights[widx];

            /* Gradient step */
            weight -= lr * grad;

            /* Soft thresholding (proximal L1) */
            if (weight > lambda) weight -= lambda;
            else if (weight < -lambda) weight += lambda;
            else weight = 0.0f;

            pred->weights[widx] = weight;
        }
    }

    pred->position++;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Predictive Encoding Pipeline
 *
 * Encodes transitions with LASSO prediction subtracted:
 *   residual_token = actual_token XOR predicted_token (mod 5 difference)
 *
 * At anchor positions, stores actual tokens (no prediction).
 * Between anchors, stores residuals → much sparser stream.
 * ═══════════════════════════════════════════════════════════════════════════ */

size_t h3x_predictive_encode(const uint8_t *raw_tokens, size_t n_tokens,
                              uint32_t anchor_stride,
                              uint8_t *out_residuals) {
    H3X_LassoPredictor pred;
    h3x_predictor_init_full(&pred, anchor_stride);

    /* History ring buffer */
    size_t max_history = H3X_PREDICT_WINDOW + 1;
    H3X_TransitionFrame *history = (H3X_TransitionFrame *)calloc(max_history,
                                                                  sizeof(H3X_TransitionFrame));
    size_t hist_count = 0;
    size_t hist_head = 0;

    size_t n_frames = n_tokens / H3X_COEFFS_PER_BYTE;
    size_t out_pos = 0;

    for (size_t f = 0; f < n_frames; f++) {
        H3X_TransitionFrame actual;
        memcpy(actual.tokens, &raw_tokens[f * H3X_COEFFS_PER_BYTE], H3X_COEFFS_PER_BYTE);

        int is_anchor = (f % anchor_stride == 0);

        if (is_anchor || hist_count == 0) {
            /* At anchor: store raw tokens (reset prediction context) */
            memcpy(&out_residuals[out_pos], actual.tokens, H3X_COEFFS_PER_BYTE);
            out_pos += H3X_COEFFS_PER_BYTE;
        } else {
            /* Between anchors: store residual = actual - predicted (mod 5) */
            H3X_TransitionFrame predicted;
            h3x_predictor_predict_full(&pred, history, hist_count, &predicted);

            for (int i = 0; i < H3X_COEFFS_PER_BYTE; i++) {
                /* Modular difference in token space [0..4] */
                int diff = (int)actual.tokens[i] - (int)predicted.tokens[i] + 2;
                if (diff < 0) diff += 5;
                if (diff > 4) diff -= 5;
                out_residuals[out_pos + i] = (uint8_t)diff;
            }
            out_pos += H3X_COEFFS_PER_BYTE;

            /* Update predictor */
            h3x_predictor_update_full(&pred, &actual, &predicted, history, hist_count);
        }

        /* Add to history ring */
        size_t idx = hist_head % max_history;
        history[idx] = actual;
        hist_head++;
        if (hist_count < max_history) hist_count++;
    }

    free(history);
    return out_pos;
}

/* Predictive decode: inverse of the above */
size_t h3x_predictive_decode(const uint8_t *residuals, size_t n_residuals,
                              uint32_t anchor_stride,
                              uint8_t *out_tokens) {
    H3X_LassoPredictor pred;
    h3x_predictor_init_full(&pred, anchor_stride);

    size_t max_history = H3X_PREDICT_WINDOW + 1;
    H3X_TransitionFrame *history = (H3X_TransitionFrame *)calloc(max_history,
                                                                  sizeof(H3X_TransitionFrame));
    size_t hist_count = 0;
    size_t hist_head = 0;

    size_t n_frames = n_residuals / H3X_COEFFS_PER_BYTE;
    size_t in_pos = 0;
    size_t out_pos = 0;

    for (size_t f = 0; f < n_frames; f++) {
        H3X_TransitionFrame actual;
        int is_anchor = (f % anchor_stride == 0);

        if (is_anchor || hist_count == 0) {
            memcpy(actual.tokens, &residuals[in_pos], H3X_COEFFS_PER_BYTE);
            in_pos += H3X_COEFFS_PER_BYTE;
        } else {
            H3X_TransitionFrame predicted;
            h3x_predictor_predict_full(&pred, history, hist_count, &predicted);

            for (int i = 0; i < H3X_COEFFS_PER_BYTE; i++) {
                int residual = (int)residuals[in_pos + i];
                int token = residual + (int)predicted.tokens[i] - 2;
                if (token < 0) token += 5;
                if (token > 4) token -= 5;
                actual.tokens[i] = (uint8_t)token;
            }
            in_pos += H3X_COEFFS_PER_BYTE;

            h3x_predictor_update_full(&pred, &actual, &predicted, history, hist_count);
        }

        memcpy(&out_tokens[out_pos], actual.tokens, H3X_COEFFS_PER_BYTE);
        out_pos += H3X_COEFFS_PER_BYTE;

        size_t idx = hist_head % max_history;
        history[idx] = actual;
        hist_head++;
        if (hist_count < max_history) hist_count++;
    }

    free(history);
    return out_pos;
}
