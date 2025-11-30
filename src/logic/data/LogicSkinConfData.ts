import {LogicCharacterData} from "./LogicCharacterData";
import {LogicData} from "./LogicData";

const brawlerIdOffset = 88;

export class LogicSkinConfData extends LogicData {
    constructor(instance: NativePointer) {
        super(instance);
    }

    public getCharacterData() {
        return new LogicCharacterData(this.instance.add(brawlerIdOffset).readPointer());
    }
}