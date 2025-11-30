import {LogicData} from "./LogicData";
import {LogicSkinConfData} from "./LogicSkinConfData";

const skinConfDataOffset = 136;

export class LogicSkinData extends LogicData {
    constructor(instance: NativePointer) {
        super(instance);
    }

    public getSkinConfData() {
        return new LogicSkinConfData(this.instance.add(skinConfDataOffset).readPointer());
    }

    public getDataByOffset(offset: number) {
        return new LogicData(this.instance.add(offset).readPointer());
    }
}