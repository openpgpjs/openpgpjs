/**
 * This file is needed to dynamic import noble-post-quantum libs.
 * Separate dynamic imports are not convenient as they result in multiple chunks,
 * which ultimately share a lot of code and need to be imported together
 * when it comes to Proton's ML-DSA + ML-KEM keys.
 * @access private
 */

export { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
export { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

