import {Libg} from "../../../libs/Libg";

const TextInput_setMaxTextLength = new NativeFunction( // in BandMailPopup::BandMailPopup after GameInputField::GameInputField ctor
    Libg.offset(0xC39988, 0xBAC81C), 'void', ['pointer', 'int']
);

export class TextInput {
    instance: NativePointer;
    protected vtable: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
        this.vtable = this.instance.readPointer();
    }

    setMaxTextLength(length: number) {
        TextInput_setMaxTextLength(this.instance, length);
    }
}