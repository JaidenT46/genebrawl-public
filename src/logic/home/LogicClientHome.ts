import {Libg} from "../../libs/Libg";
import {LogicConfData} from "./data/LogicConfData";
import {LogicGoals} from "./LogicGoals";
import {Configuration} from "../../gene/Configuration";
import {LogicDailyData} from "./data/LogicDailyData";

const LogicClientHome_isEventSlotLocked = Libg.offset(0x954354, 0x469478); // "teaser_details_container_club_league" or "power_match_locked" and find sub with (vx, 17) in args)

const SelectLocationPopup_isFutureEventEnabled = new NativeFunction(
    Libg.offset(0x64A8DC, 0x1F8C48), 'bool', ['pointer', 'int', 'bool', 'int', 'int', 'int', 'int']
);   // "RankedSeasonStart"

// Специально на будущее: first function with 2 and 3 args being vXX == 1 or 0, 5 and 6 args being vXX & 1. also it haves 0 last arg

export const logicConfDataOffset = 32;
export const logicDailyDataOffset = 24;

export class LogicClientHome {
    static patch(): void {
        LogicDailyData.patch();
        LogicConfData.patch();
        LogicGoals.patch();

        Interceptor.replace(LogicClientHome_isEventSlotLocked, new NativeCallback(function () {
            return 0;
        }, 'bool', []));

        Interceptor.replace(SelectLocationPopup_isFutureEventEnabled, new NativeCallback(function (a1,a2,a3,a4,a5,a6,a7) {
            const enabled = SelectLocationPopup_isFutureEventEnabled(a1, a2, a3, a4, a5, a6, a7);

            return !enabled ? Number(Configuration.showFutureEvents) : enabled;
        }, 'bool', ['pointer', 'int', 'bool', 'int', 'int', 'int', 'int']));
    }
}
