import {Libg} from "../../libs/Libg";

const LogicGoals_areQuestsLocked = Libg.offset(0xA13394, 0x4E0CDC); // higher than "TID_BRAWL_PASS_QUESTS_UNCLAIMED_FLOATER"

export class LogicGoals {
    static patch(): void {
        Interceptor.replace(LogicGoals_areQuestsLocked, new NativeCallback(function (logicGoals, index) {
            return 0;
        }, 'bool', ['pointer', 'int']));
    }
}