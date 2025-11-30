export class JSRandom {
    private static ALPHABET: string = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890_";

    static random(min: number, max: number) {
        return Math.round(Math.random() * (max - min)) + min;
    }

    static getRandomName() {
        return Array.from(Array(10)).map(() => this.ALPHABET[JSRandom.random(0, this.ALPHABET.length)]).join('');
    }
}