import {LogicCommand} from "./LogicCommand";

const skinDataOffset = 32;

export class LogicSelectSkinCommand extends LogicCommand {
    getSkinData(): NativePointer {
        return this.instance.add(skinDataOffset).readPointer();
    }
}