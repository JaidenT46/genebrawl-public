import {Libg} from "../../../libs/Libg";

const MapEditorModifierPopup_ctor = new NativeFunction( // "popup_editor_modifier"
    Libg.offset(0x5E5AEC, 0x1A2A7C), 'pointer', ['pointer']
);

const MapEditorModifierPopup_addModifierItem = new NativeFunction( // in ctor
    Libg.offset(0x5E638C, 0x1A31A4), 'void', ['pointer', 'int']
);

const modifiers: number[] = [
    38
];

export class MapEditorModifierPopup {
    static patch() {
        Interceptor.replace(MapEditorModifierPopup_ctor, new NativeCallback(function (self) {
            MapEditorModifierPopup_ctor(self);

            modifiers.forEach((i) => {
                MapEditorModifierPopup.addModifierItem(self, i);
            });

            return self;
        }, 'pointer', ['pointer']));
    }

    static addModifierItem(self: NativePointer, modifier: number) {
        MapEditorModifierPopup_addModifierItem(self, modifier);
    }
}
