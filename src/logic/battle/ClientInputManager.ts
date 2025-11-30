import {Libg} from "../../libs/Libg";
import {ClientInput, ClientInputType} from "./ClientInput";
import {BattleMode} from "./BattleMode";
import {Configuration} from "../../gene/Configuration";
import {LogicBattleModeClient} from "./LogicBattleModeClient";
import {LogicCharacterData} from "../data/LogicCharacterData";
import {LogicVersion} from "../LogicVersion";

const ClientInputManager_addInput = new NativeFunction( // check by ClientInput ctor
    Libg.offset(0x6746D8, 0x21C2A0), 'void', ['pointer', 'pointer']
);

const pingOffset = 48;

export class ClientInputManager {
    static patch() {
        Interceptor.replace(ClientInputManager_addInput, new NativeCallback(function (manager, input) {
            const inputType = ClientInput.getInputType(input);

            if (!Configuration.showUlti && inputType == ClientInputType.UltiEnable) {
                return;
            }

            const logicBattleModeClient = BattleMode.getLogic();

            const OwnCharacter = LogicBattleModeClient.getOwnCharacter(logicBattleModeClient);

            if (!OwnCharacter.isNull()) {
                const characterDataPtr = OwnCharacter.add(16).readPointer();
                const characterData = new LogicCharacterData(characterDataPtr);

                let shouldBeControlBlocked = false;

                if (characterData.getGlobalID() === 16000053 && Configuration.lolaControlState !== 0) {
                    switch (Configuration.lolaControlState) {
                        case 1:
                            if (inputType === ClientInputType.ControlledProjectileStopWithStick) {
                                shouldBeControlBlocked = true;
                            }
                            break;
                        case 2:
                            if (inputType === ClientInputType.Movement) {
                                shouldBeControlBlocked = true;
                            }
                            break;
                    }
                }

                if (inputType === ClientInputType.Movement && Configuration.antiknockback && LogicVersion.isNDA) {
                    ClientInputManager.addInput(
                        new ClientInput(3)
                    );
                }

                if (shouldBeControlBlocked) {
                    return;
                }

                //if (Configuration.stopLolaClone && inputType == ClientInputType.ControlledProjectileStopWithStick && characterData.getGlobalID() === 16000053) { // Lola detection
                //    return;
                //}
            }

            ClientInputManager_addInput(manager, input);
        }, 'void', ['pointer', 'pointer']));
    }

    static addInput(clientInput: ClientInput): void {
        ClientInputManager_addInput(
            BattleMode.getClientInputManager(),
            clientInput.instance
        );
    }

    static getPing(instance: NativePointer): number {
        return instance.add(pingOffset).readInt();
    }
}
