import {Libg} from "../../libs/Libg";
import {Configuration} from "../../gene/Configuration";
import {PopupBase} from "../../titan/flash/gui/PopupBase";
import {LogicVersion} from "../LogicVersion";
import {GUI} from "../../titan/flash/gui/GUI";
import {Debug} from "../../gene/Debug";
import {LocalizationManager} from "../../gene/localization";

const HomePage_startGame = new NativeFunction( // "TID_EXTRACTION_NOT_ENOUGH_TROPHIES_TO_BET" / "TID_SHUTDOWN_BATTLE_DISABLED"
    Libg.offset(0x7BEF08, 0x32E514), 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
);

const WaitingPopup_refreshCancelButton = new NativeFunction(
    Libg.offset(-1, -1), 'void', ['pointer']
);

const RandomRewardPopup_RandomRewardPopup = new NativeFunction(
    Libg.offset(-1, -1), 'void', ['pointer', 'pointer', 'pointer', 'pointer']
); // "random_reward_opening"

export class HomePage {
    static patch() {
        this.patchBackground();
        this.patchStartGame();

        /* unstable fixme
        Interceptor.replace(RandomRewardPopup_RandomRewardPopup, new NativeCallback(function (instance, data, a3, a4) {
            a4 = ptr(1)

            RandomRewardPopup_RandomRewardPopup(instance, data, a3, a4);

            instance.add(428).writeInt(1);
            return instance;
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']));*/
    }

    private static patchStartGame() {
        Interceptor.replace(HomePage_startGame, new NativeCallback(function (a1, a2, a3, a4, a5, a6, a7, a8, a9) {
            if (false) // i'll just leave this, may be useful for those who want to enable offline battles
                a4 = ptr(3);

            HomePage_startGame(a1, a2, a3, a4, a5, a6, a7, a8, a9);
        }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']));
    }

    private static patchBackground() {
        PopupBase.patch();
    }
}
