/**
 * Load script from path
 * @param {String} path
 */
export const loadScript = path => {
  if (typeof importScripts !== 'undefined') {
    return importScripts(path);
  }
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = path;
    script.onload = () => resolve();
    script.onerror = e => reject(new Error(e.message));
    document.head.appendChild(script);
  });
};

/**
 * Download script from path
 * @param {String} path fetch path
 * @param {Object} options fetch options
 */
export const dl = async function(path, options) {
  const response = await fetch(path, options);
  return response.arrayBuffer();
};
