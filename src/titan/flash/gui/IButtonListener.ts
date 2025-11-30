import {Libc} from "../../../libs/Libc";

export class IButtonListener {
    instance: NativePointer;
    protected vtable: NativePointer;
    protected nativeCallback: NativeCallback<'void', ['pointer', 'pointer']>;

    constructor(func: any) {
        this.instance = Libc.malloc(Process.pointerSize);
        this.vtable = Libc.malloc(Process.pointerSize * 2);

        this.nativeCallback = new NativeCallback(func, 'void', ['pointer', 'pointer']);
        this.vtable.add(Process.pointerSize).writePointer(this.nativeCallback);

        this.instance.writePointer(this.vtable);
    }
}