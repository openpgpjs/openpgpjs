/**
 * @module lightweight
 */

/**
 * @param {Object} params loading parameters
 * @param {Callback} cb callback
 */
const loadScriptHelper = ({ path, integrity }, cb) => {
  const script = document.createElement('script');

  script.src = path;
  if (integrity) {
    script.integrity = integrity;
  }
  script.onload = e => cb(e);
  script.onerror = e => cb(undefined, e);

  document.head.appendChild(script);
};

  /**
   * @param {String} path
   * @param {String} integrity
   */
export const loadScript = (path, integrity) => {
  // eslint-disable-next-line
    if(self.importScripts) {
    return importScripts(path);
  }
  return new Promise((resolve, reject) => {
    loadScriptHelper({ path, integrity }, (event, error) => {
      if (error) {
        return reject(error);
      }
      return resolve();
    });
  });
};


/**
 * download script from filepath
 * @param {Object} params download parameters
 */
export const dl = async function({ filepath, integrity }) {
  const options = {
    integrity,
    credentials: 'include'
  };
  const response = await fetch(filepath, options);
  return response.text();
};