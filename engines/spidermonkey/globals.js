// make check for navigator properties not fail.
var navigator = {};


// support some basic HTML5 localStorage operations
function _localStorage() {

    this.ls = {};

    this.getItem = function(key) {
        return this.ls[key] || null;
    };

    this.setItem = function(key, value) {
        this.ls[key] = value;
        return this;
    }

    return this;
}
var window = window || {};
window.localStorage = window.localStorage || _localStorage();

// support some minimal jquery need that's used for encoding messages for display in openpgp.js
function _$(foo) {

    this.text = function(txt) {
        this._txt = txt;
        return this;
    }

    this.html = function() {
        return this._txt;
    }

    return this;
}
var $ = _$;

// support undefined function in from openpgp.js
var showMessages = function(text) {
    // print(text);
}

if (!!exports) {
    exports.setShowMessages = function(fn) {
        showMessages = fn;
    };
}