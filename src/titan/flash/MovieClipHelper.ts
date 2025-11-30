import {Libg} from "../../libs/Libg";
import {TextField} from "./TextField";

const MovieClipHelper_autoAdjustChildTexts = new NativeFunction( // "TID_SETTINGS_BUTTON_WECHAT_LOGIN", then function lower with 4 args 
    Libg.offset(0x829658, 0x388E04), 'void', [ 'pointer', 'bool', 'bool', 'bool' ]
);

const MovieClipHelper_autoAdjustText = new NativeFunction( // In MovieClipHelper::autoAdjustChildTexts, first function in loop.
    Libg.offset(0x829588, 0x388D7C), 'void', ['pointer', 'bool', 'bool', 'bool']
);

const MovieClipHelper_setTextAndScaleIfNecessary = new NativeFunction( // under "TID_BATTLE_END_WAITING"
    Libg.offset(0x828D08, 0x388504), 'void', [ 'pointer', 'pointer', 'bool', 'bool' ]
);

export class MovieClipHelper {
    static autoAdjustChildTexts(movieClip: NativePointer) {
        MovieClipHelper_autoAdjustChildTexts(movieClip, 1, 0, 1);
    }

    static autoAdjustText(textField: TextField) {
        MovieClipHelper_autoAdjustText(textField.instance, 0, 1, 1);
    }

    static setTextAndScaleIfNecessary(textField: TextField, text: string) {
        MovieClipHelper_setTextAndScaleIfNecessary(textField.instance, text.scptr(), 0, 0);
    }
}