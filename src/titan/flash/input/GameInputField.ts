import {Libg} from "../../../libs/Libg";
import {TextField} from "../TextField";
import {InputField} from "./InputField";

const GameInputField_GameInputField = new NativeFunction( // "team_code_input", then search in BandMailPopup::BandMailPopup function after malloc
    Libg.offset(0x4C1610, 0xAABF4), 'void', ['pointer', 'pointer', 'pointer']
);

const GameInputField_setScaleTextIfNeed = new NativeFunction( // last function in BandMailPopup::BandMailPopup
    Libg.offset(0x4C1988, 0xAAEB8), 'void', ['pointer', 'bool']
);

const activateVtableOffset = 7 * Process.pointerSize;

export class GameInputField extends InputField {
    private readonly activateFunc: NativeFunction<void, [NativePointerValue, number]>;

    constructor(instance: NativePointer, textField: TextField, inputCaller: NativePointer) {
        GameInputField_GameInputField(instance, textField.instance, inputCaller);

        super(instance, textField);

        this.activateFunc = new NativeFunction(this.vtable.add(activateVtableOffset).readPointer(), 'void', ['pointer', 'bool']);
    }

    setScaleTextIfNeed(bool: boolean) {
        GameInputField_setScaleTextIfNeed(this.instance, Number(bool));
    }

    activate(bool: boolean) {
        this.activateFunc(this.instance, Number(bool));
    }
}
