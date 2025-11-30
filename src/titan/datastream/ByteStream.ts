import {Libc} from "../../libs/Libc";

const writeStringReferenceVtOffset = 4 * Process.pointerSize;
const writeStringVtOffset = 7 * Process.pointerSize;
const writeBooleanVtOffset = 8 * Process.pointerSize;
const writeIntVtOffset = 10 * Process.pointerSize;
const writeInt8VtOffset = 11 * Process.pointerSize;
const writeInt16VtOffset = 12 * Process.pointerSize;
const writeInt24VtOffset = 13 * Process.pointerSize;
const writeBytesVtOffset = 14 * Process.pointerSize;
const writeShortVtOffset = 15 * Process.pointerSize;
const writeVIntVtOffset = 16 * Process.pointerSize;

const readStringVtOffset = 24 * Process.pointerSize;
const readIntVtOffset = 30 * Process.pointerSize;
const readVIntVtOffset = 34 * Process.pointerSize;

export class ByteStream {
    instance: NativePointer;
    protected vtable: NativePointer;

    constructor(ptr: NativePointer) {
        this.instance = ptr;
        this.vtable = this.instance.readPointer();
    }

    writeStringReference(value: string, maxLength: number = 900000) {
        new NativeFunction(this.vtable.add(writeStringReferenceVtOffset).readPointer(), 'void', ['pointer', 'pointer', 'int'])(this.instance, value.scptr(), maxLength);
    }

    writeString(value: string, maxLength: number = 900000) {
        new NativeFunction(this.vtable.add(writeStringVtOffset).readPointer(), 'void', ['pointer', 'pointer', 'int'])(this.instance, value.scptr(), maxLength);
    }

    writeBoolean(value: boolean) {
        new NativeFunction(this.vtable.add(writeBooleanVtOffset).readPointer(), 'void', ['pointer', 'bool'])(this.instance, Number(value));
    }

    writeInt(value: number) {
        new NativeFunction(this.vtable.add(writeIntVtOffset).readPointer(), 'void', ['pointer', 'int'])(this.instance, value);
    }

    writeInt8(value: number) {
        new NativeFunction(this.vtable.add(writeInt8VtOffset).readPointer(), 'void', ['pointer', 'int'])(this.instance, value);
    }

    writeInt16(value: number) {
        new NativeFunction(this.vtable.add(writeInt16VtOffset).readPointer(), 'void', ['pointer', 'int'])(this.instance, value);
    }

    writeInt24(value: number) {
        new NativeFunction(this.vtable.add(writeInt24VtOffset).readPointer(), 'void', ['pointer', 'int'])(this.instance, value);
    }

    writeBytes(value: number[]) {
        let byteArray = Libc.malloc(value.length + 1);
        byteArray.writeByteArray(value);

        new NativeFunction(this.vtable.add(writeBytesVtOffset).readPointer(), 'void', ['pointer', 'pointer', 'int'])(this.instance, byteArray, value.length);
    }

    writeShort(value: number) {
        new NativeFunction(this.vtable.add(writeShortVtOffset).readPointer(), 'void', ['pointer', 'int'])(this.instance, value);
    }

    writeVInt(value: number) {
        new NativeFunction(this.vtable.add(writeVIntVtOffset).readPointer(), 'void', ['pointer', 'int'])(this.instance, value);
    }

    readString(maxLength: number = 900000) {
        return new NativeFunction(this.vtable.add(readStringVtOffset).readPointer(), 'pointer', ['pointer', 'int'])(this.instance, maxLength)
            .fromsc();
    }

    readInt() {
        return new NativeFunction(this.vtable.add(readIntVtOffset).readPointer(), 'int', ['pointer'])(this.instance);
    }

    readVInt() {
        return new NativeFunction(this.vtable.add(readVIntVtOffset).readPointer(), 'int', ['pointer'])(this.instance);
    }

    getLength(): number {
        const v1 = this.instance.add(20).readInt();
        const v2 = this.instance.add(24).readInt();

        return v1 <= v2 ? v2 : v1;
    }
}