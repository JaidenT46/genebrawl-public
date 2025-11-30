import {Libg} from "../../../libs/Libg";

const StreamItemList_getLastItem = new NativeFunction(
    Libg.offset(0x4FCF1C, 0xDE1E8), 'pointer', ['pointer'] // maybe just rewrite this function? it's fuck to find it.
);

export class StreamItemList {
    static getLastItem(instance: NativePointer) {
        return StreamItemList_getLastItem(instance);
    }
}
