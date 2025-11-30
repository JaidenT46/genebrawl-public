import {Libg} from "../../../libs/Libg";

const ContextMenu_addButtonType = new NativeFunction(
    Libg.offset(0x4AEB70, 0x9F9EC), 'void', ['pointer', 'pointer', 'int'] // "ContextMenu::addButtonType called with existing button type %d"
)

export class ContextMenu {
    static shouldShowContextMenu: boolean = true

    static patch() {
        Interceptor.replace(ContextMenu_addButtonType, new NativeCallback((contextMenu, buttonType, a1) => {
            if (!ContextMenu.shouldShowContextMenu) 
                return;

            ContextMenu_addButtonType(contextMenu, buttonType, a1)
        }, 'void', ['pointer', 'pointer', 'int']))
    }
}
