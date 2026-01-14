#include "source/extensions/filters/http/mcp_router/filter_config.h"

#include "envoy/secret/secret_manager.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace McpRouter {

namespace {

Secret::GenericSecretConfigProviderSharedPtr
getSecretProvider(const envoy::extensions::transport_sockets::tls::v3::SdsSecretConfig& config,
                  Server::Configuration::ServerFactoryContext& server_context,
                  Init::Manager& init_manager) {
  if (config.has_sds_config()) {
    return server_context.secretManager().findOrCreateGenericSecretProvider(
        config.sds_config(), config.name(), server_context, init_manager);
  } else {
    return server_context.secretManager().findStaticGenericSecretProvider(config.name());
  }
}

SessionIdentityConfig
parseSessionIdentity(const envoy::extensions::filters::http::mcp_router::v3::McpRouter& config) {
  SessionIdentityConfig result;

  if (!config.has_session_identity()) {
    return result;
  }

  const auto& session_identity = config.session_identity();
  const auto& identity_extractor = session_identity.identity();

  // Exactly one of header or dynamic_metadata must be set.
  if (identity_extractor.has_header()) {
    result.subject_source = HeaderSubjectSource{identity_extractor.header().name()};
  } else if (identity_extractor.has_dynamic_metadata()) {
    const auto& metadata_key = identity_extractor.dynamic_metadata().key();
    std::vector<std::string> path_keys;
    path_keys.reserve(metadata_key.path().size());
    for (const auto& segment : metadata_key.path()) {
      path_keys.push_back(segment.key());
    }
    result.subject_source = MetadataSubjectSource{metadata_key.key(), std::move(path_keys)};
  }

  if (session_identity.has_validation()) {
    switch (session_identity.validation().mode()) {
    case envoy::extensions::filters::http::mcp_router::v3::ValidationPolicy::ENFORCE:
      result.validation_mode = ValidationMode::Enforce;
      break;
    default:
      result.validation_mode = ValidationMode::Disabled;
      break;
    }
  }

  return result;
}
} // namespace

McpRouterConfig::McpRouterConfig(
    const envoy::extensions::filters::http::mcp_router::v3::McpRouter& proto_config,
    Server::Configuration::FactoryContext& context)
    : factory_context_(context), session_identity_(parseSessionIdentity(proto_config)) {
  for (const auto& server : proto_config.servers()) {
    McpBackendConfig backend;
    const auto& mcp_cluster = server.mcp_cluster();
    backend.name = server.name().empty() ? mcp_cluster.cluster() : server.name();
    backend.cluster_name = mcp_cluster.cluster();
    backend.path = mcp_cluster.path().empty() ? "/mcp" : mcp_cluster.path();
    backend.timeout =
        std::chrono::milliseconds(PROTOBUF_GET_MS_OR_DEFAULT(mcp_cluster, timeout, 5000));
    backend.host_rewrite_literal = mcp_cluster.host_rewrite_literal();
    backends_.push_back(std::move(backend));
  }

  if (backends_.size() == 1) {
    default_backend_name_ = backends_[0].name;
  }

  // Initialize encryption key provider if configured.
  if (proto_config.has_encryption_key()) {
    encryption_key_provider_ =
        getSecretProvider(proto_config.encryption_key(), context.serverFactoryContext(),
                          context.initManager());
  }
}

std::string McpRouterConfig::encryptionKey() const {
  if (encryption_key_provider_ == nullptr) {
    return "";
  }
  const auto* secret = encryption_key_provider_->secret();
  if (secret == nullptr || !secret->has_secret()) {
    return "";
  }
  const auto& data_source = secret->secret();
  if (data_source.specifier_case() ==
      envoy::config::core::v3::DataSource::SpecifierCase::kInlineBytes) {
    return data_source.inline_bytes();
  } else if (data_source.specifier_case() ==
             envoy::config::core::v3::DataSource::SpecifierCase::kInlineString) {
    return data_source.inline_string();
  }
  return "";
}

const McpBackendConfig* McpRouterConfig::findBackend(const std::string& name) const {
  for (const auto& backend : backends_) {
    if (backend.name == name) {
      return &backend;
    }
  }
  return nullptr;
}

} // namespace McpRouter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
