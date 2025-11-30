import {Libg} from "../../libs/Libg";
import {INativeDialogListener} from "./INativeDialogListener";

const nativeDialogInternal = new NativeFunction(
    Libg.offset(0xC37E10, 0xBA8188), 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
);

export class NativeDialog {
    static showNativeDialog(listener: INativeDialogListener | NativePointer, title: string, desc: string, button: string, button2: string = "", button3: string = "") {
        nativeDialogInternal(listener instanceof INativeDialogListener ? listener.instance : NULL, title.scptr(), desc.scptr(), button.scptr(), button2.scptr(), button3.scptr());
    }
}