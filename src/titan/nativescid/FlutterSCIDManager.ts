import {Libg} from "../../libs/Libg";

const FlutterSCIDManager_instance = Libg.offset(0x103E290, 0xEE64B8); // Server didn't reply to to the LoginMessage

const FlutterSCIDManager_openWindow = new NativeFunction(
    Libg.offset(0xC7ADF0, 0x955000), 'void', ['pointer', 'pointer'] // "scid_button_tutorial"
);

export class FlutterSCIDManager {
    static get instance(): NativePointer {
        return FlutterSCIDManager_instance.readPointer();
    }

    static openWindow(window: string): void {
        FlutterSCIDManager_openWindow(this.instance, window.scptr());
    }
}