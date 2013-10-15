function config_localStorage() {

  /**
   * Reads the config out of the HTML5 local storage
   * and initializes the object config.
   * if config is null the default config will be used
   */
  function read() {
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
  function write() {
    window.localStorage.setItem("config", JSON.stringify(this.config));
  }

  this.read = read;
  this.write = write;
}

module.exports = config_localStorage;
