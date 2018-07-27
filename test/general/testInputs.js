
/**
 * Generates a 64 character long javascript string out of the whole utf-8 range.
 */
function createSomeMessage(){
    const length = 50;
    let arr = [];
    for (let i= 0; i < length; i++){
        arr.push(String.fromCharCode(
            Math.floor(Math.random() * 10174) + 1));
    }
    return '  \t' + arr.join('').replace(/\r/g, '\n') + '  \t\n한국어/조선말';
}

 module.exports = {
     createSomeMessage: createSomeMessage
 };
