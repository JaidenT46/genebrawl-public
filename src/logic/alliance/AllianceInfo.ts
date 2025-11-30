import {RGBA} from "../../gene/features/RGBA";
import {LocalizationManager} from "../../gene/localization/index";
import {Libg} from "../../libs/Libg";
import {DropGUIContainer} from "../../titan/flash/gui/DropGUIContainer";
import {GUI} from "../../titan/flash/gui/GUI";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {HashTagCodeGenerator} from "../../titan/logic/util/HashTagCodeGenerator";
import {Application} from "../../titan/utils/Application";
import {AllianceFullEntry} from "./AllianceFullEntry";

const AllianceInfo_setData = new NativeFunction(
    Libg.offset(0x4DBF68, 0xC1B54), 'void', ['pointer', 'pointer'] // "TID_CLAN_INFO_NO_DESCRIPTION"
);

export class AllianceInfo {
    static copyTagButton: GameButton;
    static allianceId: number[];

    static patch() {
        Interceptor.replace(AllianceInfo_setData, new NativeCallback((allianceInfo, allianceFullEntryPtr) => {
            const allianceFullEntry = new AllianceFullEntry(allianceFullEntryPtr);
            const allianceHeaderEntry = allianceFullEntry.getAllianceHeaderEntry();
            const allianceId = allianceHeaderEntry.getAllianceId();

            AllianceInfo.allianceId = allianceId.accountId();

            AllianceInfo_setData(allianceInfo, allianceFullEntryPtr);

            const guiContainer = new DropGUIContainer(allianceInfo);
            AllianceInfo.copyTagButton = guiContainer.addGameButton("tag_stat", true);
            AllianceInfo.copyTagButton.setButtonListener(new IButtonListener(this.buttonPressed));
        }, 'void', ['pointer', 'pointer']));
    }

    static buttonPressed() {
        const allianceTag = HashTagCodeGenerator.toCode(AllianceInfo.allianceId);

        Application.copyString("#" + allianceTag);
        GUI.showFloaterText(
            LocalizationManager.getString("TAG_COPIED"),
            RGBA.green
        );
    }
}
