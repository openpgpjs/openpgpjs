/**
 * This object storing and retrieving configuration from HTML5 local storage.
 * @module config/localStorage
 */

module.exports = LocalStorage;

/**
 * @constructor
 */
function LocalStorage() {
}

/**
 * Reads the config out of the HTML5 local storage
 * and initializes the object config.
 * if config is null the default config will be used
 */
LocalStorage.prototype.read = function () {
  var cf = JSON.parse(window.localStorage.getItem("config"));
  if (cf === null) {
    this.config = this.default_config;
    this.write();
  } else
    this.config = cf;
};

/**
 * Writes the config to HTML5 local storage
 */
LocalStorage.prototype.write = function () {
  window.localStorage.setItem("config", JSON.stringify(this.config));
};
