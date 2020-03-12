
/**
 * Generates a 64 character long javascript string out of the whole utf-8 range.
 */
function createSomeMessage(){
    let arr = [];
    for (let i = 0; i < 30; i++) {
        arr.push(Math.floor(Math.random() * 10174) + 1);
    }
    for (let i = 0; i < 10; i++) {
        arr.push(0x1F600 + Math.floor(Math.random() * (0x1F64F - 0x1F600)) + 1);
    }
    return '  \t' + String.fromCodePoint(...arr).replace(/\r/g, '\n') + '  \t\n한국어/조선말';
}

module.exports = {
    createSomeMessage: createSomeMessage
};
