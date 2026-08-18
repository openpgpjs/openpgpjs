export const isSafari15or16 = () => typeof window !== 'undefined' && window.navigator.userAgent.match(/Version\/1(5|6)\.\d(\.\d)* (Mobile\/\w+ )?Safari/);

export const isSafariOrHeadlessWebKit = () => typeof window !== 'undefined' && window.navigator.userAgent.match(/WebKit/) && !window.navigator.userAgent.match(/Chrome/);
