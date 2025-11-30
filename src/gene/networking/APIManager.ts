
import {NetworkManager} from "./NetworkManager";
import {Application} from "../../titan/utils/Application";

enum State {
    NEW_KEY = -1,
    NOT_ACTIVATED = 0,
    ACTIVATED = 1,
    BANNED = 2,
    REMOVED = 9
}

export class APIManager {
    static networkManager: NetworkManager = new NetworkManager();

    static getDevice(): string {
        return Application.getDeviceType();
    }

    static doLogin(hashTag: string | null) {
        /// #if VIP
        /// #endif
    }

    static addSpectators(count: Number = 100, isLive: Boolean = false) {
        /// #if VIP
        /// #endif
    }
}