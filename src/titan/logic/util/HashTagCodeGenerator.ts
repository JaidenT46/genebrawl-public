import {Libg} from "../../../libs/Libg";
import {Configuration} from "../../../gene/Configuration";

const HashTagCodeGenerator_toCode = new NativeFunction( // "TID_SETTINGS_PLAYER_ID"
    Libg.offset(0xA07234, 0x4DA6F4), 'pointer', ['pointer', 'pointer']
);

export class HashTagCodeGenerator {
    private static playerChars: Array<string> = ["0", "2", "8", "9", "P", "Y", "L", "Q", "G", "R", "J", "C", "U", "V"];
    private static teamChars: Array<string> = ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'P', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Z', 'C', 'V', 'B', 'N', 'M', '2', '3', '4', '5', '6', '7', '8', '9'];

    static init() {

    }

    static toCode(logicLong: NativePointer | number[], useTeamChars: boolean = false) {
        const selectedChars = useTeamChars ? HashTagCodeGenerator.teamChars : HashTagCodeGenerator.playerChars;

        let id = HashTagCodeGenerator.getIdFromLogicLong(logicLong);
        let tag = "";

        while (id > 0) {
            const remainder = id % selectedChars.length;
            tag = selectedChars[remainder] + tag;
            id = (id - remainder) / selectedChars.length;
        }

        return tag;
    }

    static toId(hashtag: string, useTeamChars: boolean = false): number[] {
        const TagChar = useTeamChars ? HashTagCodeGenerator.teamChars : HashTagCodeGenerator.playerChars;

        if (!hashtag.startsWith('#') && !hashtag.startsWith("X")) {
            return [0, 0];
        }

        const TagArray = hashtag.slice(1).toUpperCase().split('');
        let Id = 0;

        for (const Character of TagArray) {
            const CharIndex = TagChar.indexOf(Character);

            if (CharIndex === -1) {
                return [0, 0];
            }

            Id *= TagChar.length;
            Id += CharIndex;
        }

        const HighLow = [];
        HighLow.push(Id % 256);
        HighLow.push((Id - HighLow[0]) / 256);

        return HighLow;
    }

    static patch() {
        this.init();

        Interceptor.replace(HashTagCodeGenerator_toCode, new NativeCallback(function (instance, logicLong) {
            const code = HashTagCodeGenerator_toCode(instance, logicLong);

            if (!Configuration.showTags)
                code.scptr("");

            return code;
        }, 'pointer', ['pointer', 'pointer']));
    }

    private static getIdFromLogicLong(logicLong: NativePointer | number[]): number {
        if (logicLong instanceof NativePointer) {
            if (logicLong.isNull()) return 0;
            const [low, high] = logicLong.accountId();
            return low + high * 256;
        } else {
            return logicLong[0] + logicLong[1] * 256;
        }
    }
}