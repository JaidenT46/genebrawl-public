
const getStreamEntryTypeOffset = 4 * 8;

const messageIdOffset = Process.pointerSize;
const senderIdOffset = Process.pointerSize * 2;

export class StreamEntry {
    instance: NativePointer;
    protected vtable: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
        this.vtable = instance.readPointer();
    }

    getSenderId() {
        return this.instance.add(senderIdOffset).readPointer().accountId();
    }

    getStreamEntryType() {
        return StreamEntry.getStreamEntryType(this.instance);
    }

    static getStreamEntryType(instance: NativePointer) {
        return new NativeFunction(instance.readPointer().add(getStreamEntryTypeOffset).readPointer(), 'int', ['pointer'])(instance);
    }
}