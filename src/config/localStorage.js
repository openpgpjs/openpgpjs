/**
 * @fileoverview Provides functions for storing and retrieving configuration from HTML5 local storage.
 * @module config/localStorage
 */

/**
 * This object is used for storing and retrieving configuration from HTML5 local storage.
 */
class LocalStorage {
  /**
   * Reads the config out of the HTML5 local storage
   * and initializes the object config.
   * if config is null the default config will be used
   */
  read() {
    const raw = globalThis.localStorage.getItem("config");
    const cf = (raw === null ? null : JSON.parse(raw));
    if (cf === null) {
      this.config = this.default_config;
      this.write();
    } else {
      this.config = cf;
    }
  }

  /**
   * Writes the config to HTML5 local storage
   */
  write() {
    globalThis.localStorage.setItem("config", JSON.stringify(this.config));
  }
}

export default LocalStorage;
