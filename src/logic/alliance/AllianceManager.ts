import {Libg} from "../../libs/Libg";

const AllianceManager_instance = Libg.offset(0x0, 0xEE61C8);

const AllianceManager_isAllianceFeatureAvailable = Libg.offset(0x4E27FC, 0xC7440); // "AllianceManager::isAllianceFeatureAvailable called with null mode"

const AllianceManager_doStartSpectate = new NativeFunction( // "TID_ERROR_SPECTATE_WAITING"
    Libg.offset(0x4E570C, 0xC8E48), 'void', ['pointer', 'pointer']
);

const AllianceManager_showPopup = new NativeFunction(
    Libg.offset(0x4E590C, 0xC9024), 'void', ['pointer']
);

export class AllianceManager {
    static getInstance(): NativePointer {
        return AllianceManager_instance.readPointer();
    }

    static patch() {
        Interceptor.replace(AllianceManager_isAllianceFeatureAvailable, new NativeCallback(function () {
            return 1;
        }, 'bool', []));
    }

    static startSpectate(logicLong: NativePointer) {
        AllianceManager_doStartSpectate(this.getInstance(), logicLong);
    }

    static showPopup(popupInstance: NativePointer) {
        AllianceManager_showPopup(popupInstance);
    }
}
