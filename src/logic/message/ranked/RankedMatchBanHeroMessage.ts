import {LogicCharacterData} from "../../data/LogicCharacterData";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";
import {PiranhaMessage} from "../PiranhaMessage";

const brawlerOffset = 144;
const unknownOffset = 152;

export class RankedMatchBanHeroMessage extends PiranhaMessage {
    constructor() {
        let instance = LogicLaserMessageFactory.createMessage(12152);

        super(instance);
    }

    setBrawler(character: LogicCharacterData) {
        this.instance.add(brawlerOffset).writePointer(character.instance);
    }

    setUnknown(int: number) {
        this.instance.add(unknownOffset).writeInt(int);
    }
}