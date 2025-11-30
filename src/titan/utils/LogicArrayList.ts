import {Libc} from "../../libs/Libc";

export class LogicArrayList {
    public instance: NativePointer;
    public arrayPtr: NativePointer;
    public array: NativePointer[];
    public capacity: number;
    public size: number;

    constructor() {
        this.instance = Libc.malloc(12);
        Libc.memset(this.instance, 0, 12);

        this.arrayPtr = Libc.malloc(4);
        this.array = [];
        this.capacity = 0; // + 4
        this.size = 0; // + 8

        this.instance.writePointer(this.arrayPtr);
    }

    update() {
        this.instance.writePointer(this.arrayPtr);
        this.instance.add(4).writeInt(this.capacity);
        this.instance.add(8).writeInt(this.size);
    }

    ensureCapacity(capacity: number) {
        if (this.size < capacity) {
            let newArray = Libc.malloc(4 * capacity);
            for (let i = 0; i < this.array.length; i++) {
                //fixme  newArray.add(4 * i).writePointer(ptr(this.array[i]));
            }

            Libc.free(this.arrayPtr);
            this.arrayPtr = newArray;
            this.capacity += capacity;
            this.update();
        }
    }

    add(value: NativePointer) {
        if (this.size == this.capacity) {
            this.ensureCapacity(this.size != 0 ? this.size * 2 : 5);
        }

        //  this.array.push(ptr(value));
        //fixme  this.arrayPtr.add(4 * this.size).writePointer(ptr(value));
        this.size += 1;
        this.update();
    }
}
