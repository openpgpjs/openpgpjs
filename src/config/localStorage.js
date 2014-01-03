/**
 * This object storing and retrieving configuration from HTML5 local storage.
 * @module config/localStorage
 */

/**
 * @constructor
 */
module.exports = function localStorage() {

  /**
   * Reads the config out of the HTML5 local storage
   * and initializes the object config.
   * if config is null the default config will be used
   */
  this.read = function () {
    var cf = JSON.parse(window.localStorage.getItem("config"));
    if (cf === null) {
      this.config = this.default_config;
      this.write();
    } else
      this.config = cf;
  }

  /**
   * Writes the config to HTML5 local storage
   */
  this.write = function () {
    window.localStorage.setItem("config", JSON.stringify(this.config));
  }
}
