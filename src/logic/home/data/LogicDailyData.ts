import {Libg} from "../../../libs/Libg";
import {Configuration} from "../../../gene/Configuration";
import {SkinChanger} from "../../../gene/features/SkinChanger";
import {HomeMode} from "../HomeMode";

const LogicDailyData_isBrawlPassPremiumUnlocked = new NativeFunction( // higher "TID_HERO_INFO_LOCKED_BP_TIER_OWNED_INFO_SHORT"
    Libg.offset(0x99B008, 0x49AB94), 'bool', ['pointer']
 );

const LogicDailyData_decode  = new NativeFunction( // LogicClientHome.decode trying to decode to an object that already has data
    Libg.offset(0x9956BC, 0x46871C), 'void', ['pointer', 'pointer']
);

const LogicDailyData_getSkin = new NativeFunction(
    Libg.offset(0x9984D4, 0x4995D0), 'pointer', ['pointer', 'pointer', 'pointer']
);

export const LogicDailyData_hasUnlockedSkin = new NativeFunction(
    Libg.offset(0x9989B0, 0x49976C), 'bool', ['pointer', 'pointer']
); // "price_legendary_trophies"

export const selectedSkinsOffset = 72;

export class LogicDailyData {
    static getSkin(character: NativePointer): NativePointer { //selected
        return LogicDailyData_getSkin(HomeMode.getPlayerData(), HomeMode.getPlayerData().add(32).readPointer(), character);
    }

    static patch(): void {
        Interceptor.replace(LogicDailyData_decode, new NativeCallback(function(dailyData, byteStream) {
            LogicDailyData_decode(dailyData, byteStream);
            
            SkinChanger.patchSelectedSkins(dailyData);
        }, 'void', ['pointer', 'pointer']));

        Interceptor.replace(LogicDailyData_isBrawlPassPremiumUnlocked, new NativeCallback(function(dailyData) {
            if (Configuration.fakePremiumPass) {
                return 1;
            }

            return LogicDailyData_isBrawlPassPremiumUnlocked(dailyData);
        }, 'bool', ['pointer']));
    }
}