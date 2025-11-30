import {LogicData} from "../../data/LogicData";
import {LogicAreaEffectClient} from "./LogicAreaEffectClient";
import {LogicCharacterClient} from "./LogicCharacterClient";
import {dataOffset, LogicGameObjectClient} from "./LogicGameObjectClient";
import {LogicItemClient} from "./LogicItemClient";
import {LogicProjectileClient} from "./LogicProjectileClient";

export class LogicGameObjectClientFactory {
    static createGameObjectByInstance(gameObject: NativePointer): LogicGameObjectClient {
        let classId = LogicData.getClassId(gameObject.add(dataOffset).readPointer());
        
        switch (classId) {
            case 6:
                return new LogicProjectileClient(gameObject);
            case 16:
                return new LogicCharacterClient(gameObject);
            case 17:
                return new LogicAreaEffectClient(gameObject);
            case 18:
                return new LogicItemClient(gameObject);
            default:
                console.error("LogicGameObjectClientFactory.createGameObjectByInstance:", "unknown class id: ", classId);
                return new LogicGameObjectClient(gameObject);
        }
    }
}