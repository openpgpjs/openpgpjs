/**
 * This file is needed to dynamic import noble-post-quantum libs.
 * Separate dynamic imports are not convenient as they result in multiple chunks,
 * which ultimately share a lot of code and need to be imported together
 * when it comes to Proton's ML-DSA + ML-KEM keys.
 */

export { ml_kem768 } from '@noble/post-quantum/ml-kem';
export { ml_dsa65 } from '@noble/post-quantum/ml-dsa';

