import {Libc} from "../../libs/Libc";

export class Rect {
    instance: NativePointer;

    constructor() {
        this.instance = Libc.malloc(16);
    }

    getWidth() {
        return this.instance.add(8).readFloat() - this.instance.readFloat();
    }

    getHeight() {
        return this.instance.add(12).readFloat() - this.instance.add(4).readFloat();
    }

    getX() {
        return this.instance.readFloat();
    }

    getY() {
        return this.instance.add(4).readFloat();
    }
}