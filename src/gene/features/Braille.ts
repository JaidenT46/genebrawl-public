const engDict: string = "qwertyuiopasdfghjklzxcvbnm" + "1234567890" + "QWERTYUIOPASDFGHJKLZXCVBNM";
const rusDict: string = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя" + "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
const brailleDict: string = "⠟⠺⠑⠗⠞⠽⠥⠊⠕⠏⠁⠎⠙⠋⠛⠓⠚⠅⠇⠵⠭⠉⠧⠃⠝⠍" +
    "⠂⠆⠒⠲⠢⠖⠶⠦⠔⠴" +
    "⠠⠟⠠⠺⠠⠑⠠⠗⠠⠞⠠⠽⠠⠥⠠⠊⠠⠕⠠⠏⠠⠁⠠⠎⠠⠙⠠⠋⠠⠛⠠⠓⠠⠚⠠⠅⠠⠇⠠⠵⠠⠭⠠⠉⠠⠧⠠⠃⠠⠝⠠⠍";

const allDict = engDict + rusDict;
const allBrailleDict = brailleDict + brailleDict;

const toBraille: { [key: string]: string; } = Object.fromEntries(allDict.split('').map((char, index) => [char, allBrailleDict[index]]));
const fromBraille: { [key: string]: string; } = Object.fromEntries(allBrailleDict.split('').map((char, index) => [char, allDict[index]]));

const ignored: string[] = [
    "t.me/gene_land",
];

export class Braille {
    static to(text: string): string {
        if (ignored.includes(text)) return text;

        return Braille.processTextWithTags(text, (plainText) =>
            plainText.toLowerCase().split('').map(char => toBraille[char] || char).join('')
        );
    }

    static from(text: string): string {
        return Braille.processTextWithTags(text, (plainText) =>
            plainText.split('').map(char => fromBraille[char] || char).join('')
        );
    }

    static isLanguageSupported(language: string): boolean {
        return Braille.getSupportedLanguages().includes(language);
    }

    static getSupportedLanguages(): string[] {
        return ["EN", "RU"];
    }

    private static processTextWithTags(
        text: string,
        transformFn: (plainText: string) => string
    ): string {
        const regex = /(<[^>]+>|[^<]+)/g;
        return text.replace(regex, (match) => {
            if (match.startsWith('<') && match.endsWith('>')) {
                return match;
            }
            return transformFn(match);
        });
    }
}