import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {Storage} from "../Storage";
import {LocalizationManager} from "../localization";
import {OwnQuestionPopup} from "../popups/OwnQuestionPopup";

export class DebugDangerousFunctionPopup extends OwnQuestionPopup {
    constructor(functionName: string) {
        super(
            LocalizationManager.getString("DANGEROUS_POPUP_TITLE"),
            LocalizationManager.getString("DANGEROUS_POPUP_BODY").replace("{functionName}", functionName)
        );

        this.addCloseButton(
            "button_no",
            LocalizationManager.getString("DANGEROUS_POPUP_BUTTON_NO")
        );

        const previousPopup = Storage.getPopup(this);

        if (previousPopup) {
            Storage.removePopupByInstance(previousPopup.instance);
        }
    }

    addYesButton(func: Function) {
        const self = this;
        this.addPopupButton(
            "button_yes",
            LocalizationManager.getString("DANGEROUS_POPUP_BUTTON_YES"),
            new IButtonListener(() => {
                func();

                self.fadeOut();
                Storage.removePopupByInstance(self.instance);
            })
        );
    }
}