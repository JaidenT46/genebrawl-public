import {Libc} from "../../libs/Libc";

export class INativeDialogListener {
    instance: NativePointer;
    protected vtable: NativePointer;
    protected nativeCallback: NativeCallback<'void', ['pointer', 'int']>;

    constructor(func: any) {
        this.instance = Libc.malloc(Process.pointerSize);
        this.vtable = Libc.malloc(Process.pointerSize);
        this.nativeCallback = new NativeCallback(func, 'void', ['pointer', 'int']);

        this.vtable.writePointer(this.nativeCallback);

        this.instance.writePointer(this.vtable);
    }
}