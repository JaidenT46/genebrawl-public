import {Libc} from "../../libs/Libc";

export class LogicLong {
    instance: NativePointer;

    get high() {
        return this.instance.readInt();
    }

    get low() {
        return this.instance.add(4).readInt();
    }

    constructor(high: number = 0, low: number = 0) {
        this.instance = Libc.malloc(8);

        this.instance.writeInt(high);
        this.instance.add(4).writeInt(low);
    }
}