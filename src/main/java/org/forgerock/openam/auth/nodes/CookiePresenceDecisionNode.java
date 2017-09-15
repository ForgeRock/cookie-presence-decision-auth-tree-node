/*
 * simon.moffatt@forgerock.com
 *
 * Checks for the presence of the named cookie in the authentication request.  Doesn't check cookie value, only presence
 */

package org.forgerock.openam.auth.nodes;

import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.inject.assistedinject.Assisted;

//smoff
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Node.Metadata(outcomeProvider = CookiePresenceDecisionNode.OutcomeProvider.class,
        configClass = CookiePresenceDecisionNode.Config.class)
public class CookiePresenceDecisionNode implements Node {

    private final static String TRUE_OUTCOME_ID = "true";
    private final static String FALSE_OUTCOME_ID = "false";
    private final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Configuration for the node.
     */

    public interface Config {
        /**
         * The name of the HTTP header we want to look for.
         * @return the name.
         */
        @Attribute(order = 100)
        default String cookieName() {
            return "My-Cookie";
        }

    }

    private final Config config;

    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public CookiePresenceDecisionNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
	
	//Pull cookies out of headers
	List<String> cookies = context.headers.get("Cookie");
	logger.info("CookiePresenceCheckNode cookies found: " + cookies);

	//If no cookies present at all        
	if (cookies.size() != 1) {
	
		logger.info("CookiePresenceCheckNode no cookies found");
                return goTo(false).build();
        }

	//Take first entry of [] to make string and see if specified cookie name exists...
	if(cookies.get(0).contains(config.cookieName())){
       		
		logger.info("CookiePresenceCheckNode cookie called " + config.cookieName() + " found!");
		return goTo(true).build();
	}
	
	//Cookie not present
	return goTo(false).build();

    }

    private Action.ActionBuilder goTo(boolean outcome) {
        return Action.goTo(outcome ? TRUE_OUTCOME_ID : FALSE_OUTCOME_ID);
    }

    static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        private static final String BUNDLE = CookiePresenceDecisionNode.class.getName().replace(".", "/");

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(TRUE_OUTCOME_ID, bundle.getString("trueOutcome")),
                    new Outcome(FALSE_OUTCOME_ID, bundle.getString("falseOutcome")));
        }
    }
}
