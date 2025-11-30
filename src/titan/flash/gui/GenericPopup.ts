import {Libc} from "../../../libs/Libc";
import {Libg} from "../../../libs/Libg";
import {GameButton} from "./GameButton";
import {PopupBase} from "./PopupBase";

const GenericPopup_GenericPopup = new NativeFunction( // "popup_center"
    Libg.offset(0x5C53F0, 0x186E10), 'void', ['pointer', 'pointer', 'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer']
);

const GenericPopup_setTitle = new NativeFunction( // under "TID_BLING_CAP_REACHED_TITLE"
    Libg.offset(0x5C5960, 0x186EF4), 'void', ['pointer', 'pointer']
);

const GenericPopup_setTitleTid = new NativeFunction( // function after "TID_BAND_MAIL_POPUP_TITLE"
    Libg.offset(0x5C58D4, 0x186EB0), 'void', ['pointer', 'pointer'] // блять тоесть вы хотите мне сказать что есть 2 функции которые делают одно и то же но одна просто тид конвертирует?
);

const GenericPopup_addButtonWithText = new NativeFunction( // in BandMailPopup::BandMailPopup function with 4 args (3rd is number 1)
    Libg.offset(0x5C6474, 0x1873F0), 'pointer', ['pointer', 'pointer', 'int', 'pointer']
);

const GenericPopup_addButton = new NativeFunction( // in BandMailPopup::BandMailPopup function with 3 args (3rd is number 2)
    Libg.offset(0x5C62D4, 0x187354), 'pointer', ['pointer', 'pointer', 'int']
);

export class GenericPopup extends PopupBase {
    constructor(exportName: string) {
        //super("sc/ui.sc", exportName)
        const instance = Libc.malloc(472);

        GenericPopup_GenericPopup(instance, exportName.scptr(), 0, 0, "".scptr(), "".scptr(), "".scptr(), "".scptr());
        super(instance);
    }

    setTitleTid(title: string) {
        GenericPopup_setTitleTid(this.instance, title.scptr());
    }

    setTitle(title: string) {
        GenericPopup_setTitle(this.instance, title.scptr());
    }

    addButtonWithText(exportName: string, type: number, text: string) {
        return new GameButton(
            GenericPopup_addButtonWithText(this.instance, exportName.scptr(), type, text.scptr())
        );
    }

    addButton(exportName: string, type: number) {
        return new GameButton(
            GenericPopup_addButton(this.instance, exportName.scptr(), type)
        );
    }

    static setTitle(instance: NativePointer, title: string) {
        GenericPopup_setTitle(instance, title.scptr());
    }
}
