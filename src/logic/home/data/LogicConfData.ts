import {Libg} from "../../../libs/Libg";
import {Configuration} from "../../../gene/Configuration";
import {GlobalID} from "../../data/GlobalID";
import {LogicDataTables} from "../../data/LogicDataTables";
import {LogicThemeData} from "../../data/LogicThemeData";
import {Storage} from "../../../gene/Storage";

const LogicConfData_getIntValue = new NativeFunction( // higher "shader/impostor_outline_glitch.vsh"
    Libg.offset(0x993DE8, 0x496ED0), 'int', ['pointer', 'int', 'int']
);

export class LogicConfData {
    static patch(): void {
        Interceptor.replace(LogicConfData_getIntValue, new NativeCallback(function(confData, key, defaultValue) {
            if (key === 1) {
                Storage.serverThemeId = defaultValue
            }

            if (Configuration.themeId !== -1 && key === 1) { // Check if theme was disabled. If it was, changing theme to server.
                const themeId = GlobalID.getInstanceID(Configuration.themeId);

                const themeData = LogicDataTables.getDataById(41, themeId) as LogicThemeData;

                if (themeData.isDisabled()) {
                    Configuration.themeId = -1;
                    Configuration.save();
                }
            }

            const patches: { [key: number]: number } = {
                1: Configuration.themeId !== -1 ? Configuration.themeId : -228,
                12: !Configuration.specialOffers ? 1 : -228,
                15: !Configuration.contentCreatorBoost ? 1 : -228,
                19: !Configuration.specialOffers ? 1 : -228,
                22: !Configuration.specialOffers ? 1 : -228,
                93: !Configuration.specialOffers ? 1 : -228,
                96: !Configuration.specialOffers ? 1 : -228,
                46: 1
            };

            if (patches.hasOwnProperty(key) && patches[key] != -228) {
                return patches[key];
            }

            return LogicConfData_getIntValue(confData, key, defaultValue);
        }, 'int', ['pointer', 'int', 'int']));
    }

    static getIntValue(confData: NativePointer, key: number, defaultValue: number): number {
        return LogicConfData_getIntValue(confData, key, defaultValue);
    }
}