import {LogicCharacterClient} from "./LogicCharacterClient";
import {Libg} from "../../../libs/Libg";

const skillListOffset = 112;

const LogicCharacterClientOwn_getNextSkillClient = new NativeFunction(
    Libg.offset(0x901A00, 0x42A250), 'pointer', ['pointer', 'pointer']
);

const LogicCharacterClientOwn_moveToWithClientPrediction = new NativeFunction(
    Libg.offset(0x0, 0x42974C), 'void', ['pointer', 'int', 'int', 'bool', 'pointer']
);

export class LogicCharacterClientOwn extends LogicCharacterClient {
    static getNextSkillClient(logicCharacterClientOwn: NativePointer, playerPtr: NativePointer): NativePointer {
        return LogicCharacterClientOwn_getNextSkillClient(logicCharacterClientOwn, playerPtr);
    }

    static getSkill(logicCharacterClientOwn: NativePointer, index: number) {
        return logicCharacterClientOwn.add(skillListOffset).readPointer().add(index * Process.pointerSize).readPointer();
    }

    getSkill(index: number) {
        return LogicCharacterClientOwn.getSkill(this.instance, index);
    }

    moveToWithClientPrediction(x: number, y: number, z: number, logicBattleModeClient: NativePointer) {
        LogicCharacterClientOwn_moveToWithClientPrediction(this.instance, x, y, logicBattleModeClient.add(276).readU8(), logicBattleModeClient);
    }
}