#pragma once

#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "json.hpp"

using nlohmann::json;

#define JSON_SERIALIZABLE(...)                                                 \
  static const bool _json_serializable = true;                                 \
  auto _json_field_names() const { return _field_names(#__VA_ARGS__); }        \
  auto _json_fields_r() { return std::tie(__VA_ARGS__); }                      \
  auto _json_fields_w() const { return std::make_tuple(__VA_ARGS__); }

std::vector<std::string>
_field_names(const std::string& comma_separated_fields)
{
  std::istringstream iss(comma_separated_fields);
  std::vector<std::string> fields(std::istream_iterator<std::string>{ iss },
                                  std::istream_iterator<std::string>());

  for (auto& field : fields) {
    field.erase(field.find_last_not_of(",") + 1);
  }
  return fields;
}

template<std::size_t I = 0, typename... Tp>
inline std::enable_if_t<I == sizeof...(Tp), void>
tuple_to_json(const std::vector<std::string>& names,
              json& j,
              const std::tuple<Tp...>& t)
{}

template<std::size_t I = 0, typename... Tp>
  inline std::enable_if_t < I<sizeof...(Tp), void>
                            tuple_to_json(const std::vector<std::string>& names,
                                          json& j,
                                          const std::tuple<Tp...>& t)
{
  j[names[I]] = std::get<I>(t);
  tuple_to_json<I + 1>(names, j, t);
}

template<typename T>
inline std::enable_if_t<T::_json_serializable, void>
to_json(json& j, const T& obj)
{
  tuple_to_json(obj._json_field_names(), j, obj._json_fields_w());
}

template<std::size_t I = 0, typename... Tp>
inline std::enable_if_t<I == sizeof...(Tp), void>
tuple_from_json(const std::vector<std::string>& names,
                const json& j,
                std::tuple<Tp...>& t)
{}

template<std::size_t I = 0, typename... Tp>
  inline std::enable_if_t <
  I<sizeof...(Tp), void>
  tuple_from_json(const std::vector<std::string>& names,
                  const json& j,
                  std::tuple<Tp...>& t)
{
  using curr_type_ref = std::tuple_element_t<I, std::tuple<Tp...>>;
  using curr_type = std::remove_reference_t<curr_type_ref>;

  // XXX: This is currently lazy all the time; it would be nice to be able to be
  // strict sometimes.
  if (j.find(names[I]) != j.end()) {
    std::get<I>(t) = j[names[I]].get<curr_type>();
  }
  tuple_from_json<I + 1>(names, j, t);
}

template<typename T>
inline std::enable_if_t<T::_json_serializable, void>
from_json(const json& j, T& obj)
{
  auto fields = obj._json_fields_r();
  return tuple_from_json(obj._json_field_names(), j, fields);
}
