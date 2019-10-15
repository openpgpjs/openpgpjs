/**
 * @param {String} path
 * @param {String} integrity
 */
export const loadScript = (path, integrity) => {
  if(typeof importScripts !== 'undefined') {
    return importScripts(path);
  }
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = path;
    if (integrity) {
      script.integrity = integrity;
    }
    script.onload = () => resolve();
    script.onerror = e => reject(e);
    document.head.appendChild(script);
  });
};

/**
 * download script from filepath
 * @param {Object} params download parameters
 */
export const dl = async function(filepath, options) {
  const response = await fetch(filepath, options);
  return response.text();
};